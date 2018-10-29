[logo]: https://www.xy.company/img/home/logo_xy.png

![logo]

# sdk-core-kotlin

[![](https://jitpack.io/v/XYOracleNetwork/sdk-core-kotlin.svg)](https://jitpack.io/#XYOracleNetwork/sdk-core-kotlin) [![](https://img.shields.io/gitter/room/XYOracleNetwork/Stardust.svg)](https://gitter.im/XYOracleNetwork/Dev) [![Maintainability](https://api.codeclimate.com/v1/badges/af641257b27ecea22a9f/maintainability)](https://codeclimate.com/github/XYOracleNetwork/sdk-core-kotlin/maintainability)

| Branches        | Status           |
| ------------- |:-------------:|
| Master      | [![](https://circleci.com/gh/XYOracleNetwork/sdk-core-kotlin.svg?style=shield)](https://circleci.com/gh/XYOracleNetwork/sdk-core-kotlin) |
| Develop      | [![](https://circleci.com/gh/XYOracleNetwork/sdk-core-kotlin/tree/develop.svg?style=shield)](https://circleci.com/gh/XYOracleNetwork/sdk-core-kotlin/tree/develop)      |

A library to preform all basic XYO Network functions.
This includes creating an origin chain, maintaining an origin chain, negotiations for talking to other nodes, and other basic functionality.
The library has heavily abstracted modules so that all operations will work with any crypto, storage, networking, ect.

## Installing
You can add sdk-core-kotlin to your existing app by cloning the project and manually adding it to your build.gradle or by using JitPack:

```
git clone git@github.com:XYOracleNetwork/sdk-core-kotlin.git
```

```gradle
dependencies {
    implementation 'com.github.XYOracleNetwork:sdk-core-kotlin:v0.1.0-beta'
}
```

#### Prerequisites
* JDK 1.8
* Kotlin

## License
This project is licensed under the MIT License - see the LICENSE.md file for details
