package com.stegolab.stegobox;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.provider.OpenableColumns;
import android.provider.Settings;
import android.text.InputType;
import android.webkit.MimeTypeMap;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.materialswitch.MaterialSwitch;
import com.google.android.material.progressindicator.LinearProgressIndicator;
import com.google.android.material.textfield.MaterialAutoCompleteTextView;
import com.google.android.material.textfield.TextInputLayout;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.PickVisualMediaRequest;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.documentfile.provider.DocumentFile;

import com.stegolab.stegobox.container.Envelope;
import com.stegolab.stegobox.crypto.Crypto;
import com.stegolab.stegobox.crypto.Kdf;
import com.stegolab.stegobox.stego.LsbStego;
import com.stegolab.stegobox.stego.TailAppend;
import com.stegolab.stegobox.util.ZipUtil;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class MainActivity extends AppCompatActivity {

    private static final int REQ_COVER = 1;
    private static final int REQ_FILES = 2;
    private static final int REQ_OUT_HIDE = 3;
    private static final int REQ_STEGO = 4;
    private static final int REQ_OUT_FILE = 5;
    private static final int REQ_OUT_DIR = 6;
    private static final int REQ_PICK_DIR = 7;
    private static final int REQ_ADD_IMAGE = 8;

    private static final String[] CARRIERS = {"尾部追加（容量大，需无损传输）", "像素 LSB（改动像素，需 PNG）"};
    private static final String[] CIPHERS = {"AES-256-GCM", "ChaCha20-Poly1305", "SM4-GCM (国密)", "不加密"};
    private static final int[] CIPHER_IDS = {Crypto.AES, Crypto.CHACHA, Crypto.SM4, Crypto.NONE};
    private static final String[] KEY_MODES = {"手写口令", "随机口令", "无口令"};
    private static final String[] RECV_MODES = {"手动输入", "自动输入（图片输入）"};

    private MaterialAutoCompleteTextView ddCarrier, ddCipher, ddKeyMode, ddRecv;
    private TextInputLayout tilPassword;
    private MaterialSwitch chkFixedDir;
    private MaterialButton btnHide, btnExtract, btnSelfTest, btnGrantAll;
    private LinearProgressIndicator progress;
    private EditText editPassword, editText;
    private TextView txtCover, txtFiles, txtDir, log, txtStatus, txtPerm;
    private int selCarrier, selCipher, selKeyMode, selRecv;
    private volatile boolean busy = false;
    private int pendingPickReq = REQ_COVER;
    private ActivityResultLauncher<PickVisualMediaRequest> photoPicker;
    private ActivityResultLauncher<PickVisualMediaRequest> multiPhotoPicker;
    private SharedPreferences prefs;
    private Uri outDirUri;
    private byte[] lastHash;

    private Uri coverUri;
    private final List<Uri> fileUris = new ArrayList<>();

    // pending hide job (so a random password is generated once)
    private int pCarrier, pCipher, pEnvKeyMode;
    private String pPw, pName;
    private byte[] pPlain;

    private byte[] extractedPayload;
    private Envelope extractedEnvelope;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        ddCarrier = findViewById(R.id.ddCarrier);
        ddCipher = findViewById(R.id.ddCipher);
        ddKeyMode = findViewById(R.id.ddKeyMode);
        ddRecv = findViewById(R.id.ddRecv);
        tilPassword = findViewById(R.id.tilPassword);
        editPassword = findViewById(R.id.editPassword);
        editText = findViewById(R.id.editText);
        txtCover = findViewById(R.id.txtCover);
        txtFiles = findViewById(R.id.txtFiles);
        log = findViewById(R.id.log);

        setupDropdown(ddCarrier, CARRIERS, p -> selCarrier = p);
        setupDropdown(ddCipher, CIPHERS, p -> selCipher = p);
        setupDropdown(ddKeyMode, KEY_MODES, p -> selKeyMode = p);
        setupDropdown(ddRecv, RECV_MODES, p -> selRecv = p);

        findViewById(R.id.btnCopyPw).setOnClickListener(v -> copyPassword());

        chkFixedDir = findViewById(R.id.chkFixedDir);
        txtDir = findViewById(R.id.txtDir);
        prefs = getSharedPreferences("stegobox", MODE_PRIVATE);
        String dirStr = prefs.getString("outDir", null);
        if (dirStr != null) {
            outDirUri = Uri.parse(dirStr);
            txtDir.setText("当前：" + shortPath(outDirUri));
        } else {
            txtDir.setText("(未设置)");
        }
        chkFixedDir.setChecked(prefs.getBoolean("useFixedDir", false));
        chkFixedDir.setOnCheckedChangeListener((b, v) -> prefs.edit().putBoolean("useFixedDir", v).apply());
        findViewById(R.id.btnPickDir).setOnClickListener(v -> {
            Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
            i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION
                    | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                    | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
            startActivityForResult(i, REQ_PICK_DIR);
        });
        findViewById(R.id.btnManageFiles).setOnClickListener(v -> manageFiles());

        progress = findViewById(R.id.progress);
        txtStatus = findViewById(R.id.txtStatus);
        txtPerm = findViewById(R.id.txtPerm);
        btnHide = findViewById(R.id.btnHide);
        btnExtract = findViewById(R.id.btnExtract);
        btnSelfTest = findViewById(R.id.btnSelfTest);
        btnGrantAll = findViewById(R.id.btnGrantAll);

        btnSelfTest.setOnClickListener(v -> runSelfTest());
        findViewById(R.id.btnPickCover).setOnClickListener(v -> pickCover());
        findViewById(R.id.btnPickFiles).setOnClickListener(v -> pickFiles());
        btnHide.setOnClickListener(v -> startHide());
        btnExtract.setOnClickListener(v -> pickStego());
        btnGrantAll.setOnClickListener(v -> requestAllFilesPermission());

        // System photo picker (Android 13+ / GMS back-port). Falls back to ACTION_PICK in pickImage().
        photoPicker = registerForActivityResult(new ActivityResultContracts.PickVisualMedia(), uri -> {
            if (uri == null) return;
            if (pendingPickReq == REQ_STEGO) {
                setBusy(true, "读取图片…");
                performExtract(uri);
            } else {
                coverUri = uri;
                txtCover.setText(nameOf(uri));
            }
        });

        // Multi-select photo picker -> appended to the payload list
        multiPhotoPicker = registerForActivityResult(
                new ActivityResultContracts.PickMultipleVisualMedia(100), uris -> {
                    if (uris == null || uris.isEmpty()) return;
                    for (Uri u : uris) if (u != null) fileUris.add(u);
                    txtFiles.setText(fileUris.size() + " 个文件");
                    refreshFilesLabel();
                    log("已选择 " + fileUris.size() + " 个文件");
                    toast("已选择 " + fileUris.size() + " 个文件");
                });

        findViewById(R.id.btnPickImages).setOnClickListener(v -> pickImagesFromGallery());

        log("就绪。算法：" + Crypto.name(Crypto.AES) + " / " + Crypto.name(Crypto.CHACHA)
                + " / " + Crypto.name(Crypto.SM4));
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshPermUi();
    }

    private void setupDropdown(MaterialAutoCompleteTextView dd, String[] items,
                               java.util.function.IntConsumer onSelect) {
        dd.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, items));
        dd.setText(items[0], false);
        dd.setOnItemClickListener((parent, view, position, id) -> onSelect.accept(position));
        onSelect.accept(0);
    }

    // ---------------------------------------------------------------- pickers

    private void pickFiles() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        i.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
        startActivityForResult(i, REQ_FILES);
    }

    private void pickCover() {
        pendingPickReq = REQ_COVER;
        pickImage();
    }

    private void pickStego() {
        if (busy) { toast("正在处理，请稍候…"); return; }
        pendingPickReq = REQ_STEGO;
        pickImage();
    }

    /**
     * Prefer the system photo picker (Android 13+, or back-ported via Play services on 11+),
     * which shows a thumbnail gallery. Fall back to ACTION_PICK, which also opens a gallery
     * app rather than the documents/file manager UI.
     */
    private void pickImage() {
        // 1) system photo picker (Android 13+, or GMS back-port)
        try {
            if (photoPicker != null
                    && ActivityResultContracts.PickVisualMedia.isPhotoPickerAvailable(this)) {
                photoPicker.launch(new PickVisualMediaRequest.Builder()
                        .setMediaType(ActivityResultContracts.PickVisualMedia.ImageOnly.INSTANCE)
                        .build());
                return;
            }
        } catch (Throwable ignored) {
        }
        // 2) ACTION_PICK over the MediaStore image collection -> opens the GALLERY app.
        launchGalleryPick(pendingPickReq);
    }

    /**
     * Open the gallery to pick ONE image.
     * ACTION_PICK with a MediaStore collection uri is the documented "pick from gallery" intent;
     * the type-only variant gets routed to the documents/file-manager UI on some OEM builds.
     */
    private void launchGalleryPick(int req) {
        try {
            Intent pick = new Intent(Intent.ACTION_PICK, MediaStore.Images.Media.EXTERNAL_CONTENT_URI);
            pick.setType("image/*");
            startActivityForResult(pick, req);
            return;
        } catch (Throwable ignored) {
        }
        try {
            Intent pick2 = new Intent(Intent.ACTION_PICK);
            pick2.setType("image/*");
            startActivityForResult(pick2, req);
            return;
        } catch (Throwable ignored) {
        }
        try {
            Intent get = new Intent(Intent.ACTION_GET_CONTENT);
            get.setType("image/*");
            startActivityForResult(get, req);
        } catch (Throwable t) {
            fail("无法打开图片选择器", t);
        }
    }

    /** Add photos from the gallery to the payload list. */
    private void pickImagesFromGallery() {
        if (busy) { toast("正在处理，请稍候…"); return; }
        // 1) real multi-select when the system photo picker exists (Android 13+ / GMS backport)
        try {
            if (multiPhotoPicker != null
                    && ActivityResultContracts.PickVisualMedia.isPhotoPickerAvailable(this)) {
                multiPhotoPicker.launch(new PickVisualMediaRequest.Builder()
                        .setMediaType(ActivityResultContracts.PickVisualMedia.ImageOnly.INSTANCE)
                        .build());
                return;
            }
        } catch (Throwable ignored) {
        }
        // 2) otherwise: ACTION_PICK over the MediaStore image collection -> opens the GALLERY app.
        launchGalleryPick(REQ_ADD_IMAGE);
    }

    // ---------------------------------------------------------------- hide

    private void startHide() {
        if (busy) { toast("正在处理，请稍候…"); return; }
        if (coverUri == null) { toast("请先选择封面图片"); return; }

        pCarrier = selCarrier;
        pCipher = CIPHER_IDS[selCipher];
        int keySel = selKeyMode;                                    // 0手写 1随机 2无口令
        int recvSel = selRecv;                                      // 0手动 1自动

        if (keySel == 2) {                                          // 无口令 => 不加密
            if (pCipher != Crypto.NONE) log("「无口令」已自动改为不加密（无密钥可用）。");
            pCipher = Crypto.NONE;
        }

        if (pCipher == Crypto.NONE) {
            pEnvKeyMode = Envelope.KEY_NONE;
            pPw = "";
        } else {
            if (keySel == 0) {
                pPw = editPassword.getText().toString();
                if (pPw.isEmpty()) { toast("请输入口令"); return; }
            } else {
                pPw = randomPassword();
                editPassword.setText(pPw);
                setPwVisible(true);
            }
            pEnvKeyMode = (recvSel == 1) ? Envelope.KEY_EMBEDDED : Envelope.KEY_PASSWORD;
        }

        final String textPayload = editText.getText().toString().trim();
        if (textPayload.isEmpty() && fileUris.isEmpty()) { toast("请选择文件或输入文本"); return; }

        setBusy(true, "读取内容…");
        new Thread(() -> {
            try {
                buildPlain(textPayload);                            // heavy I/O -> never on UI thread
                if (pCarrier == Envelope.CARRIER_LSB) checkLsbCapacity();

                ui(() -> {
                    try {
                        if (fixedDirActive()) {                       // 用户指定的目录优先
                            setBusy(true, "写入中…");
                            performHideToDir();
                        } else if (canWriteDirect()) {
                            setBusy(true, "写入中…");
                            performHideDirect();
                        } else {
                            setBusy(true, "选择保存位置…");
                            Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                            i.addCategory(Intent.CATEGORY_OPENABLE);
                            i.setType("image/png");
                            i.putExtra(Intent.EXTRA_TITLE, "stegobox_out.png");
                            startActivityForResult(i, REQ_OUT_HIDE);
                        }
                    } catch (Throwable t) {
                        fail("启动失败", t);
                    }
                });
            } catch (Throwable t) {
                fail("准备失败", t);
            }
        }).start();
    }

    /** Bounds-only decode: reads just the image header so huge covers cannot OOM. */
    private void checkLsbCapacity() throws Exception {
        byte[] head = readHead(coverUri, 128 * 1024);
        BitmapFactory.Options o = new BitmapFactory.Options();
        o.inJustDecodeBounds = true;
        BitmapFactory.decodeByteArray(head, 0, head.length, o);
        if (o.outWidth <= 0 || o.outHeight <= 0) {
            throw new IllegalArgumentException("无法读取封面图片尺寸（文件可能过大或格式不支持）");
        }
        long cap = (long) o.outWidth * o.outHeight * 3 / 8;
        long need = pPlain.length + 4096;
        if (need > cap) {
            throw new IllegalArgumentException("图片容量不足：最多 " + cap + " 字节，需要约 " + need
                    + " 字节。请换更大的图，或改用「尾部追加」（无容量上限）。");
        }
    }

    /** Build the plaintext + payload name from the current inputs (text and/or multiple files). */
    private void buildPlain(String textPayload) throws Exception {
        List<String> names = new ArrayList<>();
        List<byte[]> datas = new ArrayList<>();

        if (!textPayload.isEmpty()) {
            names.add("message.txt");
            datas.add(textPayload.getBytes("UTF-8"));
        }
        for (Uri u : fileUris) {
            names.add(nameOf(u));
            datas.add(readAll(u));
        }

        if (datas.isEmpty()) throw new IllegalArgumentException("没有可隐藏的内容");
        if (datas.size() == 1) {
            pPlain = datas.get(0);
            pName = names.get(0);
        } else {
            pPlain = ZipUtil.zip(names.toArray(new String[0]), datas.toArray(new byte[0][]));
            pName = null;                                            // bundle => 还原成多个文件
        }
    }

    // ---------------------------------------------------------------- activity result

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != Activity.RESULT_OK || data == null) {
            // cancelled (or empty result): never leave the UI stuck in the "busy" state
            if (resultCode != Activity.RESULT_OK) setBusy(false, null);
            return;
        }

        // IMPORTANT: multi-select returns a ClipData while getData() is NULL,
        // so this must be handled BEFORE any getData() null-check.
        if (requestCode == REQ_FILES) {
            final ClipData clip = data.getClipData();
            fileUris.clear();
            if (clip != null) {
                for (int k = 0; k < clip.getItemCount(); k++) {
                    Uri u = clip.getItemAt(k).getUri();
                    if (u != null) fileUris.add(u);
                }
            } else if (data.getData() != null) {
                fileUris.add(data.getData());
            }
            final int n = fileUris.size();
            txtFiles.setText(n == 0 ? "(未选择)" : n + " 个文件");
            refreshFilesLabel();
            log("已选择 " + n + " 个文件");
            toast(n == 0 ? "未选择文件" : "已选择 " + n + " 个文件");
            return;
        }

        Uri uri = data.getData();
        if (uri == null) return;

        switch (requestCode) {
            case REQ_COVER:
                coverUri = uri;
                txtCover.setText(nameOf(uri));
                break;
            case REQ_ADD_IMAGE:
                fileUris.add(uri);
                txtFiles.setText(fileUris.size() + " 个文件");
                refreshFilesLabel();
                log("已添加 1 张（共 " + fileUris.size() + " 个文件）");
                toast("已添加，共 " + fileUris.size() + " 个文件");
                break;
            case REQ_OUT_HIDE:
                performHide(uri);
                break;
            case REQ_STEGO:
                setBusy(true, "读取图片…");
                performExtract(uri);
                break;
            case REQ_OUT_FILE:
                try {
                    writeTo(uri, extractedPayload);
                    setBusy(false, null);
                    toast("提取完成 ✓");
                    log("已还原文件 → " + nameOf(uri) + "（" + extractedPayload.length + " 字节）");
                } catch (Throwable t) {
                    fail("保存失败", t);
                }
                break;
            case REQ_OUT_DIR:
                restoreBundle(uri);
                break;
            case REQ_PICK_DIR:
                try {
                    getContentResolver().takePersistableUriPermission(uri,
                            Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
                } catch (Exception ignored) { }
                outDirUri = uri;
                prefs.edit().putString("outDir", uri.toString()).putBoolean("useFixedDir", true).apply();
                chkFixedDir.setChecked(true);
                txtDir.setText("当前：" + shortPath(uri));
                log("输出目录已设置：之后不再弹选择框。");
                break;
        }
    }

    private byte[] computeHideOutput() throws Exception {
        byte[] cover = readAll(coverUri);
        Envelope env = Envelope.build(pCarrier, pCipher, pEnvKeyMode, pPw, pName, pPlain);
        lastHash = env.hash;
        if (pCarrier == Envelope.CARRIER_APPEND) {
            return TailAppend.embed(cover, env);
        }
        Bitmap bmp = BitmapFactory.decodeByteArray(cover, 0, cover.length);
        if (bmp == null) throw new IllegalArgumentException("无法解码封面图片");
        Bitmap stego = LsbStego.embed(flatten(bmp), env.serialize());
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        stego.compress(Bitmap.CompressFormat.PNG, 100, bos);
        return bos.toByteArray();
    }

    private void logHideOk(String where) {
        ui(() -> {
            setBusy(false, null);
            log("隐藏成功。载体=" + (pCarrier == Envelope.CARRIER_APPEND ? "尾部追加" : "像素LSB")
                    + " | 算法=" + Crypto.name(pCipher)
                    + " | 接收=" + (pEnvKeyMode == Envelope.KEY_EMBEDDED ? "自动输入" : "手动输入"));
            log("明文 " + pPlain.length + " 字节 | SHA-256 " + Kdf.hex(lastHash).substring(0, 16) + "…");
            log("输出：" + where);
            if (pEnvKeyMode != Envelope.KEY_NONE) {
                log(pEnvKeyMode == Envelope.KEY_EMBEDDED
                        ? "口令已填入「口令」栏（对方无需输入；口令随文件保存，无安全性）。"
                        : "口令已填入「口令」栏，请分享给接收方。");
            }
            toast("隐藏完成 ✓");
        });
    }

    private void performHide(Uri outUri) {
        new Thread(() -> {
            try {
                byte[] out = computeHideOutput();
                writeTo(outUri, out);
                logHideOk("已保存（" + out.length + " 字节）");
            } catch (Throwable t) {
                fail("隐藏失败", t);
            }
        }).start();
    }

    private void performHideToDir() {
        new Thread(() -> {
            try {
                byte[] out = computeHideOutput();
                String where = writeIntoFixedDir("stegobox_out.png", "image/png", out);
                logHideOk(where + "（" + out.length + " 字节）");
            } catch (Throwable t) {
                fail("隐藏失败", t);
            }
        }).start();
    }

    private void performHideDirect() {
        new Thread(() -> {
            try {
                byte[] out = computeHideOutput();
                File f = directOutFile("stegobox_out.png");
                writeFile(f, out);
                logHideOk(f.getAbsolutePath() + "（" + out.length + " 字节）");
            } catch (Throwable t) {
                fail("隐藏失败", t);
            }
        }).start();
    }

    // ---------------------------------------------------------------- extract / restore

    private void performExtract(Uri stegoUri) {
        String pw = editPassword.getText().toString();
        new Thread(() -> {
            try {
                byte[] data = readAll(stegoUri);

                Envelope env = Envelope.findEnvelope(data);
                if (env == null) {
                    Bitmap bmp = BitmapFactory.decodeByteArray(data, 0, data.length);
                    if (bmp != null) {
                        byte[] inner = LsbStego.extract(bmp);
                        if (inner != null) env = Envelope.parse(inner, 0);
                    }
                }
                if (env == null) throw new IllegalArgumentException("未在该图片中找到 StegoBox 数据");

                final Envelope e = env;
                byte[] plain = e.decrypt(pw);
                extractedPayload = plain;
                extractedEnvelope = e;

                ui(() -> {
                    log("发现载荷 —— " + (e.carrier == Envelope.CARRIER_APPEND ? "尾部追加" : "像素LSB")
                            + " | " + Crypto.name(e.cipher)
                            + " | " + keyModeName(e.keyMode));
                    log("SHA-256 校验通过，明文 " + plain.length + " 字节。");
                });

                if (fixedDirActive()) {                       // 用户指定的目录优先
                    File dirFile = canWriteDirect() ? treeUriToFile(outDirUri) : null;
                    if (e.isBundle()) {
                        Map<String, byte[]> entries = ZipUtil.unzip(plain);
                        ui(() -> log("多文件包（" + entries.size() + " 项），正在还原到指定目录…"));
                        if (dirFile != null) restoreBundleIntoFile(dirFile);
                        else restoreBundleInto(DocumentFile.fromTreeUri(this, outDirUri));
                    } else {
                        String where = writeIntoFixedDir(e.payloadName, mimeOf(e.payloadName), plain);
                        ui(() -> {
                            log("已还原 → " + where + "（" + plain.length + " 字节）");
                            toast("提取完成 ✓");
                            setBusy(false, null);
                        });
                    }
                } else if (canWriteDirect()) {
                    File root = directOutRoot();
                    if (e.isBundle()) {
                        Map<String, byte[]> entries = ZipUtil.unzip(plain);
                        ui(() -> log("多文件包（" + entries.size() + " 项），正在还原…"));
                        restoreBundleIntoFile(root);
                    } else {
                        File f = directOutFile(e.payloadName);
                        writeFile(f, plain);
                        ui(() -> {
                            log("已还原 → " + f.getName() + "（" + plain.length + " 字节）");
                            toast("提取完成 ✓");
                            setBusy(false, null);
                        });
                    }
                } else if (e.isBundle()) {
                    Map<String, byte[]> entries = ZipUtil.unzip(plain);
                    ui(() -> log("这是一个多文件包，共 " + entries.size() + " 项，请选择保存目录以还原。"));
                    Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
                    ui(() -> startActivityForResult(i, REQ_OUT_DIR));
                } else {
                    Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                    i.addCategory(Intent.CATEGORY_OPENABLE);
                    i.setType(mimeOf(e.payloadName));
                    i.putExtra(Intent.EXTRA_TITLE, e.payloadName);
                    ui(() -> startActivityForResult(i, REQ_OUT_FILE));
                }
            } catch (Throwable t) {
                fail("提取失败", t);
            }
        }).start();
    }

    private void restoreBundle(Uri treeUri) {
        restoreBundleInto(DocumentFile.fromTreeUri(this, treeUri));
    }

    private void restoreBundleInto(final DocumentFile rootDir) {
        new Thread(() -> {
            try {
                Map<String, byte[]> entries = ZipUtil.unzip(extractedPayload);
                if (rootDir == null) throw new IllegalArgumentException("无法访问所选目录");
                DocumentFile root = rootDir;

                int ok = 0;
                for (Map.Entry<String, byte[]> en : new LinkedHashMap<>(entries).entrySet()) {
                    String path = ZipUtil.safe(en.getKey());
                    if (path.isEmpty()) continue;
                    String[] seg = path.split("/");
                    DocumentFile dir = root;
                    for (int i = 0; i < seg.length - 1; i++) {
                        DocumentFile next = dir.findFile(seg[i]);
                        if (next == null) next = dir.createDirectory(seg[i]);
                        if (next == null) throw new IllegalArgumentException("无法创建目录 " + seg[i]);
                        dir = next;
                    }
                    String fname = seg[seg.length - 1];
                    DocumentFile old = dir.findFile(fname);
                    if (old != null) old.delete();
                    DocumentFile f = dir.createFile(mimeOf(fname), fname);
                    if (f == null) throw new IllegalArgumentException("无法创建文件 " + fname);
                    try (OutputStream os = getContentResolver().openOutputStream(f.getUri())) {
                        os.write(en.getValue());
                    }
                    ok++;
                }
                final int n = ok;
                ui(() -> {
                    log("已还原 " + n + " 个文件。");
                    toast("提取完成 ✓");
                    setBusy(false, null);
                });
            } catch (Throwable t) {
                fail("还原失败", t);
            }
        }).start();
    }

    private static String keyModeName(int km) {
        switch (km) {
            case Envelope.KEY_PASSWORD: return "口令·手动输入";
            case Envelope.KEY_EMBEDDED: return "口令·自动输入";
            default: return "无口令";
        }
    }

    // ---------------------------------------------------------------- io helpers

    private byte[] readAll(Uri uri) throws Exception {
        try (InputStream in = getContentResolver().openInputStream(uri)) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[16384];
            int n;
            while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
            return bos.toByteArray();
        }
    }

    /** Writes and PROPAGATES failures — callers must not report success on a failed write. */
    private void writeTo(Uri uri, byte[] data) throws Exception {
        try (OutputStream os = getContentResolver().openOutputStream(uri)) {
            if (os == null) throw new IOException("无法打开输出流（URI 无效）");
            os.write(data);
            os.flush();
        }
    }

    /**
     * Real display name of a SAF document. getLastPathSegment() is NOT a file name
     * (providers return opaque ids like "image_294428"), so query DISPLAY_NAME instead,
     * and if the name carries no extension, append one from the MIME type.
     */
    private String nameOf(Uri uri) {
        if (uri == null) return "file.bin";
        String name = null;
        try (Cursor c = getContentResolver().query(uri, null, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                int idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (idx >= 0) {
                    String v = c.getString(idx);
                    if (v != null && !v.trim().isEmpty()) name = v.trim();
                }
            }
        } catch (Exception ignored) {
        }
        if (name == null) {
            try {
                DocumentFile df = DocumentFile.fromSingleUri(this, uri);
                if (df != null && df.getName() != null) name = df.getName();
            } catch (Exception ignored) {
            }
        }
        if (name == null) {
            String seg = uri.getLastPathSegment();
            name = (seg == null) ? "file.bin" : seg;
        }
        return ensureExtension(name, uri);
    }

    /** If the name has no extension, append one derived from the document's MIME type. */
    private String ensureExtension(String name, Uri uri) {
        if (name == null || name.isEmpty()) return "file.bin";
        int slash = name.lastIndexOf('/');
        if (slash >= 0) name = name.substring(slash + 1);
        if (name.contains(".")) return name;
        try {
            String mime = getContentResolver().getType(uri);
            String ext = (mime == null) ? null : MimeTypeMap.getSingleton().getExtensionFromMimeType(mime);
            if (ext == null) {
                // common image fallbacks (providers sometimes report octet-stream)
                String n = name.toLowerCase();
                if (n.startsWith("screenshot") || n.startsWith("img") || n.startsWith("image")
                        || n.startsWith("photo") || n.startsWith("微信图片")) {
                    ext = "jpg";
                }
            }
            if (ext != null && !ext.isEmpty()) return name + "." + ext;
        } catch (Exception ignored) {
        }
        return name;
    }

    private static String mimeOf(String name) {
        if (name == null) return "application/octet-stream";
        String n = name.toLowerCase();
        if (n.endsWith(".png")) return "image/png";
        if (n.endsWith(".jpg") || n.endsWith(".jpeg")) return "image/jpeg";
        if (n.endsWith(".gif")) return "image/gif";
        if (n.endsWith(".webp")) return "image/webp";
        if (n.endsWith(".mp4")) return "video/mp4";
        if (n.endsWith(".mp3")) return "audio/mpeg";
        if (n.endsWith(".pdf")) return "application/pdf";
        if (n.endsWith(".zip")) return "application/zip";
        if (n.endsWith(".apk")) return "application/vnd.android.package-archive";
        if (n.endsWith(".txt") || n.endsWith(".md")) return "text/plain";
        if (n.endsWith(".json")) return "application/json";
        return "application/octet-stream";
    }

    private static String randomPassword() {
        final String alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        SecureRandom r = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) sb.append(alphabet.charAt(r.nextInt(alphabet.length())));
        return sb.toString();
    }

    private void ui(Runnable r) {
        runOnUiThread(r);
    }

    private void copyPassword() {
        String pw = editPassword.getText().toString();
        if (pw.isEmpty()) { toast("当前没有口令"); return; }
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText("stegobox-password", pw));
        toast("口令已复制到剪切板");
    }

    /** Reveal / hide the password text (the eye icon can still toggle it afterwards). */
    private void setPwVisible(boolean visible) {
        int sel = editPassword.getText().length();
        editPassword.setInputType(visible
                ? (InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)
                : (InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD));
        if (sel >= 0) editPassword.setSelection(sel);
    }

    // ---------------------------------------------------------------- fixed output dir

    private boolean fixedDirActive() {
        return chkFixedDir != null && chkFixedDir.isChecked() && outDirUri != null;
    }

    private Uri newFileInFixedDir(String name, String mime) throws Exception {
        DocumentFile dir = DocumentFile.fromTreeUri(this, outDirUri);
        if (dir == null) throw new IOException("输出目录不可用，请重新选择");
        String safe = (name == null || name.isEmpty()) ? "stegobox_out.png" : name;
        DocumentFile old = dir.findFile(safe);
        if (old != null) old.delete();
        DocumentFile f = dir.createFile(mime, safe);
        if (f == null) throw new IOException("无法在目录中创建 " + safe);
        return f.getUri();
    }

    /**
     * Write into the user-chosen fixed directory.
     * When "all files access" is granted we resolve the SAF tree to a real path and use plain
     * file IO (more reliable than SAF, and immune to temporary-grant issues); otherwise we
     * fall back to a SAF DocumentFile write.
     */
    private String writeIntoFixedDir(String name, String mime, byte[] data) throws Exception {
        String safe = (name == null || name.isEmpty()) ? "stegobox_out.png" : name;
        if (canWriteDirect()) {
            File dir = treeUriToFile(outDirUri);
            if (dir != null && (dir.exists() || dir.mkdirs())) {
                File f = new File(dir, safe);
                if (f.exists()) f.delete();
                writeFile(f, data);
                return f.getAbsolutePath();
            }
        }
        Uri u = newFileInFixedDir(safe, mime);
        writeTo(u, data);
        return "固定目录 / " + safe;
    }

    /** Map a SAF tree uri (from ACTION_OPEN_DOCUMENT_TREE) to a real filesystem path, if possible. */
    private File treeUriToFile(Uri treeUri) {
        try {
            String docId = android.provider.DocumentsContract.getTreeDocumentId(treeUri);
            int c = docId.indexOf(':');
            if (c < 0) return null;
            String vol = docId.substring(0, c);
            String rel = docId.substring(c + 1);
            if (rel.contains("..")) return null;
            File base = "primary".equalsIgnoreCase(vol)
                    ? Environment.getExternalStorageDirectory()
                    : new File("/storage/" + vol);
            return rel.isEmpty() ? base : new File(base, rel);
        } catch (Throwable t) {
            return null;
        }
    }

    private static String shortPath(Uri uri) {
        if (uri == null) return "(未设置)";
        String s = uri.getLastPathSegment();
        if (s == null) return uri.toString();
        int c = s.indexOf(':');
        return c >= 0 ? s.substring(c + 1) : s;
    }

    /**
     * Flatten transparency onto a white background. Needed before LSB embedding because
     * ARGB_8888 bitmaps are premultiplied: with alpha < 255 the colour channels get scaled,
     * which silently corrupts the embedded bits.
     */
    private static Bitmap flatten(Bitmap src) {
        if (src == null || !src.hasAlpha()) return src;
        Bitmap out = Bitmap.createBitmap(src.getWidth(), src.getHeight(), Bitmap.Config.ARGB_8888);
        Canvas c = new Canvas(out);
        c.drawColor(Color.WHITE);
        c.drawBitmap(src, 0, 0, null);
        return out;
    }

    // ---------------------------------------------------------------- file list

    /** Immediate feedback on selection, then resolve real file names in the background. */
    private void refreshFilesLabel() {
        final int n = fileUris.size();
        if (n == 0) { txtFiles.setText("(未选择)"); return; }
        txtFiles.setText(n + " 个文件已选择…");
        toast("已选择 " + n + " 个文件");
        log("已选择 " + n + " 个文件");
        new Thread(() -> {
            StringBuilder sb = new StringBuilder("已选择 " + n + " 个文件：\n");
            int shown = Math.min(n, 5);
            for (int i = 0; i < shown && i < fileUris.size(); i++) {
                sb.append("• ").append(nameOf(fileUris.get(i))).append("\n");
            }
            if (n > shown) sb.append("… 其余 ").append(n - shown).append(" 个");
            final String s = sb.toString();
            ui(() -> txtFiles.setText(s));
        }).start();
    }

    private void manageFiles() {
        if (busy) { toast("正在处理，请稍候…"); return; }
        if (fileUris.isEmpty()) { toast("还没有选择文件"); return; }
        setBusy(true, "读取文件列表…");
        new Thread(() -> {
            final String[] items = new String[fileUris.size()];
            for (int i = 0; i < items.length; i++) items[i] = nameOf(fileUris.get(i));
            ui(() -> {
                setBusy(false, null);
                showManageDialog(items);
            });
        }).start();
    }

    private void showManageDialog(final String[] items) {
        final boolean[] keep = new boolean[items.length];
        java.util.Arrays.fill(keep, true);
        new AlertDialog.Builder(this)
                .setTitle("勾选=保留，取消勾选=移除")
                .setMultiChoiceItems(items, keep, (d, which, checked) -> keep[which] = checked)
                .setPositiveButton("确定", (d, w) -> {
                    List<Uri> remain = new ArrayList<>();
                    for (int i = 0; i < keep.length; i++) if (keep[i]) remain.add(fileUris.get(i));
                    fileUris.clear();
                    fileUris.addAll(remain);
                    txtFiles.setText(fileUris.isEmpty() ? "(未选择)" : fileUris.size() + " 个文件");
                })
                .setNeutralButton("全部清除", (d, w) -> {
                    fileUris.clear();
                    txtFiles.setText("(未选择)");
                })
                .show();
    }

    private void runSelfTest() {
        new Thread(() -> {
            StringBuilder sb = new StringBuilder();
            int pass = 0, fail = 0;
            try {
                byte[] secret = "StegoBox 自检 / 国密SM4 / round-trip".getBytes("UTF-8");
                int[] ciphers = {Crypto.AES, Crypto.CHACHA, Crypto.SM4};
                int[] modes = {Envelope.KEY_PASSWORD, Envelope.KEY_EMBEDDED};
                for (int c : ciphers) {
                    for (int m : modes) {
                        String tag = Crypto.name(c) + (m == Envelope.KEY_EMBEDDED ? " / 自动" : " / 手动");
                        try {
                            Envelope e = Envelope.build(Envelope.CARRIER_APPEND, c, m, "pw", "selftest.txt", secret);
                            Envelope p = Envelope.parse(e.serialize(), 0);
                            boolean ok = p != null && "selftest.txt".equals(p.payloadName)
                                    && Arrays.equals(p.decrypt("pw"), secret);
                            sb.append(ok ? "✓ " : "✗ ").append(tag).append("\n");
                            if (ok) pass++; else fail++;
                        } catch (Throwable t) {
                            sb.append("✗ ").append(tag).append(" -> ").append(t.getMessage()).append("\n");
                            fail++;
                        }
                    }
                }

                // tail-append round-trip
                try {
                    byte[] cover = new byte[2048];
                    new SecureRandom().nextBytes(cover);
                    Envelope e = Envelope.build(0, Crypto.AES, Envelope.KEY_PASSWORD, "pw", "x.bin", secret);
                    boolean ok = Arrays.equals(TailAppend.extract(TailAppend.embed(cover, e)).decrypt("pw"), secret);
                    sb.append(ok ? "✓ " : "✗ ").append("尾部追加往返\n");
                    if (ok) pass++; else fail++;
                } catch (Throwable t) {
                    sb.append("✗ 尾部追加往返 -> ").append(t.getMessage()).append("\n");
                    fail++;
                }

                // pixel LSB round-trip
                try {
                    Bitmap bmp = Bitmap.createBitmap(64, 64, Bitmap.Config.ARGB_8888);
                    Envelope e = Envelope.build(1, Crypto.SM4, Envelope.KEY_PASSWORD, "pw", "y.txt", secret);
                    Bitmap st = LsbStego.embed(bmp, e.serialize());
                    byte[] back = LsbStego.extract(st);
                    boolean ok = back != null && Arrays.equals(Envelope.parse(back, 0).decrypt("pw"), secret);
                    sb.append(ok ? "✓ " : "✗ ").append("像素LSB往返\n");
                    if (ok) pass++; else fail++;
                } catch (Throwable t) {
                    sb.append("✗ 像素LSB往返 -> ").append(t.getMessage()).append("\n");
                    fail++;
                }
            } catch (Throwable t) {
                sb.append("异常: ").append(t).append("\n");
                fail++;
            }
            final String out = "自检：通过 " + pass + " / 失败 " + fail + "\n" + sb;
            ui(() -> log(out));
        }).start();
    }

    // ---------------------------------------------------------------- busy / errors

    private void setBusy(boolean b, String label) {
        busy = b;
        if (btnHide != null) {
            btnHide.setEnabled(!b);
            btnHide.setText(b ? (label == null ? "处理中…" : label) : "隐藏并生成图片");
        }
        if (btnExtract != null) btnExtract.setEnabled(!b);
        if (btnSelfTest != null) btnSelfTest.setEnabled(!b);
        if (progress != null) progress.setVisibility(b ? android.view.View.VISIBLE : android.view.View.GONE);
        if (txtStatus != null) {
            txtStatus.setVisibility(b ? android.view.View.VISIBLE : android.view.View.GONE);
            if (b) txtStatus.setText(label == null ? "处理中…" : label);
        }
    }

    private void fail(String prefix, Throwable t) {
        final String msg = (t instanceof OutOfMemoryError)
                ? "内存不足（图片或文件过大）；请改用「尾部追加」，或减少一次选择的文件数量"
                : (t.getClass().getSimpleName() + "：" + (t.getMessage() == null ? "未知错误" : t.getMessage()));
        ui(() -> {
            setBusy(false, null);
            log(prefix + "：" + msg);
            toast(prefix);
        });
    }

    // ---------------------------------------------------------------- all-files access

    private boolean canWriteDirect() {
        if (Build.VERSION.SDK_INT >= 30) return Environment.isExternalStorageManager();
        return checkSelfPermission(android.Manifest.permission.WRITE_EXTERNAL_STORAGE)
                == PackageManager.PERMISSION_GRANTED;
    }

    private File directOutRoot() {
        File d = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "StegoBox");
        if (!d.exists()) d.mkdirs();
        return d;
    }

    private File directOutFile(String name) {
        String safe = (name == null || name.isEmpty()) ? "stegobox_out.png" : name;
        File f = new File(directOutRoot(), safe);
        if (f.exists()) f.delete();
        return f;
    }

    private void writeFile(File f, byte[] data) throws IOException {
        File p = f.getParentFile();
        if (p != null && !p.exists()) p.mkdirs();
        try (FileOutputStream os = new FileOutputStream(f)) {
            os.write(data);
        }
    }

    private void requestAllFilesPermission() {
        if (Build.VERSION.SDK_INT >= 30) {
            if (Environment.isExternalStorageManager()) { toast("已拥有所有文件访问权限"); return; }
            try {
                startActivity(new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                        Uri.parse("package:" + getPackageName())));
            } catch (Exception e) {
                try {
                    startActivity(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
                } catch (Exception e2) {
                    toast("无法打开权限设置，请手动开启");
                }
            }
        } else {
            requestPermissions(new String[]{
                    android.Manifest.permission.WRITE_EXTERNAL_STORAGE,
                    android.Manifest.permission.READ_EXTERNAL_STORAGE}, 1001);
        }
    }

    private void refreshPermUi() {
        if (txtPerm == null) return;
        boolean ok = canWriteDirect();
        txtPerm.setText(ok ? "权限：已授予（直接输出到 Download/StegoBox）"
                : "权限：未授予 —— 建议点下方按钮授权，避免目录授权失效");
        txtPerm.setTextColor(ok ? 0xFF1B5E20 : 0xFFB3261E);
        if (btnGrantAll != null) btnGrantAll.setEnabled(!ok);
    }

    private void restoreBundleIntoFile(final File root) {
        new Thread(() -> {
            try {
                Map<String, byte[]> entries = ZipUtil.unzip(extractedPayload);
                int ok = 0;
                for (Map.Entry<String, byte[]> en : new LinkedHashMap<>(entries).entrySet()) {
                    String path = ZipUtil.safe(en.getKey());
                    if (path.isEmpty()) continue;
                    File f = new File(root, path);
                    File p = f.getParentFile();
                    if (p != null && !p.exists()) p.mkdirs();
                    try (FileOutputStream os = new FileOutputStream(f)) {
                        os.write(en.getValue());
                    }
                    ok++;
                }
                final int n = ok;
                ui(() -> {
                    log("已还原 " + n + " 个文件到 " + root.getAbsolutePath());
                    toast("提取完成 ✓");
                    setBusy(false, null);
                });
            } catch (Throwable t) {
                fail("还原失败", t);
            }
        }).start();
    }

    /** Read at most {@code max} bytes from the start of a document (for header-only decoding). */
    private byte[] readHead(Uri uri, int max) throws Exception {
        try (InputStream in = getContentResolver().openInputStream(uri)) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n, total = 0;
            while (total < max && (n = in.read(buf)) > 0) {
                int take = Math.min(n, max - total);
                bos.write(buf, 0, take);
                total += take;
            }
            return bos.toByteArray();
        }
    }

    private void log(String s) {
        log.append(s + "\n");
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_SHORT).show();
    }
}