from flask import Flask, flash, request, redirect, url_for
import json
import ezkl
import os
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = '/home/benjamin/circuit_breaker/frontend/packages/nextjs/app/api/files'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/hello', methods=['GET'])
def hello_world():
    return {"value":"Hello, World!","blabla":"bouboub"}

model_path = os.path.join(app.config['UPLOAD_FOLDER'],'network_lenet.onnx')
compiled_model_path = os.path.join(app.config['UPLOAD_FOLDER'],'network.compiled')
pk_path = os.path.join(app.config['UPLOAD_FOLDER'],'key.pk')
vk_path = os.path.join(app.config['UPLOAD_FOLDER'],'key.vk')
settings_path = os.path.join(app.config['UPLOAD_FOLDER'],'settings.json')
witness_path = os.path.join(app.config['UPLOAD_FOLDER'],'witness.json')
data_path = os.path.join(app.config['UPLOAD_FOLDER'],'input.json')
proof_path = os.path.join(app.config['UPLOAD_FOLDER'],'test.pf')

@app.route('/genwitness', methods=['POST'])
def genwitness():
    if request.method == 'POST':
        # check if the post request has the file part
        for filename in request.files:
            file = request.files[filename]
            if file.filename == '':
                print("filename empty")
            else:
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    res = ezkl.gen_witness(data_path, compiled_model_path, witness_path)
    assert os.path.isfile(witness_path)
    os.remove(witness_path)
    os.remove(settings_path)
    os.remove(data_path)
    os.remove(compiled_model_path)
        
    print(res)
    return res

@app.route('/prove', methods=['POST'])
def prove():
    if request.method == 'POST':
        # check if the post request has the file part
        for filename in request.files:
            file = request.files[filename]
            if file.filename == '':
                print("filename empty")
            else:
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    # res = ezkl.setup(
    #     compiled_model_path,
    #     vk_path,
    #     pk_path,
    # )

    # assert res == True
    # assert os.path.isfile(vk_path)
    # assert os.path.isfile(pk_path)
    # assert os.path.isfile(settings_path)
    res = ezkl.prove(
        witness_path,
        compiled_model_path,
        pk_path,
        proof_path,
        "single",
    )

    assert os.path.isfile(proof_path)
    os.remove(witness_path)
    os.remove(pk_path)
    os.remove(compiled_model_path)
    os.remove(proof_path)
    print(res)
    return res

if __name__ == '__main__':
    app.run(port=5328)