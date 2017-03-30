#!groovy​

@Library('SovrinHelpers') _

def name = 'stp'

def testUbuntu = {
    try {
        echo 'Ubuntu Test: Checkout csm'
        checkout scm

        echo 'Ubuntu Test: Build docker image'
        def testEnv = dockerHelpers.build(name)

        testEnv.inside {
            echo 'Ubuntu Test: Install dependencies'
            testHelpers.installDeps(['raet', 'BitVector'])

            echo 'Ubuntu Test: Test'
            testHelpers.testJunit()
        }
    }
    finally {
        echo 'Ubuntu Test: Cleanup'
        step([$class: 'WsCleanup'])
    }
}

def testWindows = {
    echo "TODO: not implemented"
}

def testWindowsNoDocker = {
    try {
        echo 'Windows No Docker Test: Checkout csm'
        checkout scm   

        testHelpers.createVirtualEnvAndExecute({ python, pip ->
            echo 'Windows No Docker Test: Install dependencies'
            testHelpers.installDepsBat(python, pip, ['raet', 'BitVector'])
            
            echo 'Windows No Docker Test: Test'
            // XXX temporary, until issues with tests will be resolved
            // (some tests fail and seems it hangs out pytest)
            timeout(time: 60, unit: 'SECONDS') {
                testHelpers.testJunitBat(python, pip)
            }
        })
    }
    finally {
        echo 'Windows No Docker Test: Cleanup'
        step([$class: 'WsCleanup'])
    }
}

//testAndPublish(name, [ubuntu: testUbuntu, windows: testWindowsNoDocker, windowsNoDocker: testWindowsNoDocker])
testAndPublish(name, [ubuntu: testUbuntu])
