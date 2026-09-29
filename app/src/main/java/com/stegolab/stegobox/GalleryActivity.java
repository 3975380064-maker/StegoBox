package com.stegolab.stegobox;

import android.content.ContentUris;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.util.LruCache;
import android.util.Size;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.GridView;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Built-in gallery picker: a real thumbnail grid backed by MediaStore.
 *
 * We ship our own picker because on some ROMs (e.g. HONOR/EMUI on Android 12) both
 * ACTION_PICK and ACTION_GET_CONTENT are routed to the *documents/file manager* UI,
 * and the system photo picker requires Android 13 or GMS.
 */
public class GalleryActivity extends AppCompatActivity {

    public static final String EXTRA_MULTI = "multi";
    public static final String RESULT_URIS = "uris";

    private final List<Uri> all = new ArrayList<>();
    private final LinkedHashSet<Uri> selected = new LinkedHashSet<>();
    private final LruCache<String, Bitmap> cache = new LruCache<>(80);
    private final HashMap<String, Bitmap> ready = new HashMap<>();
    private final Set<String> inFlight = Collections.synchronizedSet(new HashSet<String>());
    private final ExecutorService pool = Executors.newFixedThreadPool(4);

    private GridView grid;
    private TextView empty, title, hint;
    private ImgAdapter adapter;
    private boolean multi = true;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_gallery);

        multi = getIntent().getBooleanExtra(EXTRA_MULTI, true);
        title = findViewById(R.id.title);
        hint = findViewById(R.id.hint);
        empty = findViewById(R.id.empty);
        grid = findViewById(R.id.grid);

        hint.setText(multi ? "点按选择 / 取消，选好后点右上角「完成」" : "点按一张图片即可");
        updateTitle();

        adapter = new ImgAdapter();
        grid.setAdapter(adapter);
        grid.setOnItemClickListener((parent, view, position, id) -> {
            if (position < 0 || position >= all.size()) return;
            Uri u = all.get(position);
            if (!multi) {
                finishWith(new ArrayList<>(Collections.singletonList(u)));
                return;
            }
            if (!selected.add(u)) selected.remove(u);
            updateTitle();
            adapter.notifyDataSetChanged();
        });

        findViewById(R.id.btnDone).setOnClickListener(v -> {
            if (selected.isEmpty()) { toast("还没有选择图片"); return; }
            finishWith(new ArrayList<>(selected));
        });

        if (hasMediaPermission()) load();
        else requestMediaPermission();
    }

    private void updateTitle() {
        title.setText(multi
                ? (selected.isEmpty() ? "选择图片（可多选）" : "已选 " + selected.size() + " 张")
                : "选择图片");
    }

    private void finishWith(ArrayList<Uri> uris) {
        Intent r = new Intent();
        r.putExtra(RESULT_URIS, uris);
        setResult(RESULT_OK, r);
        finish();
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_SHORT).show();
    }

    // ------------------------------------------------------------------ permission

    private boolean hasMediaPermission() {
        if (Build.VERSION.SDK_INT >= 33) {
            return checkSelfPermission(android.Manifest.permission.READ_MEDIA_IMAGES)
                    == PackageManager.PERMISSION_GRANTED;
        }
        return checkSelfPermission(android.Manifest.permission.READ_EXTERNAL_STORAGE)
                == PackageManager.PERMISSION_GRANTED
                || Environment.isExternalStorageManager();
    }

    private void requestMediaPermission() {
        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(new String[]{android.Manifest.permission.READ_MEDIA_IMAGES}, 42);
        } else {
            requestPermissions(new String[]{android.Manifest.permission.READ_EXTERNAL_STORAGE}, 42);
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != 42) return;
        if (hasMediaPermission()) load();
        else empty.setVisibility(View.VISIBLE);
    }

    // ------------------------------------------------------------------ loading

    private void load() {
        new Thread(() -> {
            final List<Uri> found = new ArrayList<>();
            try {
                Uri col = MediaStore.Images.Media.EXTERNAL_CONTENT_URI;
                String[] proj = {MediaStore.Images.Media._ID};
                try (Cursor c = getContentResolver().query(col, proj, null, null,
                        MediaStore.Images.Media.DATE_ADDED + " DESC")) {
                    if (c != null) {
                        int idc = c.getColumnIndexOrThrow(MediaStore.Images.Media._ID);
                        while (c.moveToNext() && found.size() < 1000) {
                            found.add(ContentUris.withAppendedId(col, c.getLong(idc)));
                        }
                    }
                }
            } catch (Throwable ignored) {
            }
            runOnUiThread(() -> {
                all.clear();
                all.addAll(found);
                adapter.notifyDataSetChanged();
                empty.setVisibility(found.isEmpty() ? View.VISIBLE : View.GONE);
            });
        }).start();
    }

    private void loadThumb(Uri u) {
        final String key = u.toString();
        if (ready.containsKey(key) || cache.get(key) != null) return;
        if (!inFlight.add(key)) return;
        pool.execute(() -> {
            Bitmap bm = null;
            try {
                bm = getContentResolver().loadThumbnail(u, new Size(240, 240), null);
            } catch (Throwable ignored) {
            }
            if (bm != null) cache.put(key, bm);
            final Bitmap b = bm;
            inFlight.remove(key);
            if (b != null) runOnUiThread(() -> {
                ready.put(key, b);
                adapter.notifyDataSetChanged();
            });
        });
    }

    private class ImgAdapter extends BaseAdapter {
        @Override public int getCount() { return all.size(); }
        @Override public Object getItem(int i) { return all.get(i); }
        @Override public long getItemId(int i) { return i; }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            if (convertView == null) {
                convertView = LayoutInflater.from(GalleryActivity.this)
                        .inflate(R.layout.item_gallery, parent, false);
            }
            ImageView thumb = convertView.findViewById(R.id.thumb);
            ImageView check = convertView.findViewById(R.id.check);
            Uri u = all.get(position);
            String key = u.toString();

            Bitmap b = ready.get(key);
            if (b == null) b = cache.get(key);
            if (b != null) {
                thumb.setImageBitmap(b);
            } else {
                thumb.setImageDrawable(null);
                loadThumb(u);
            }
            check.setVisibility(selected.contains(u) ? View.VISIBLE : View.GONE);
            return convertView;
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        pool.shutdownNow();
    }
}