# bctls-jdk18on-ja3

bctls-jdk18on-ja3

## Getting Started

### Installing

```xml
<dependency>
  <groupId>com.github.leeyazhou</groupId>
  <artifactId>bctls-jdk18on-ja3-shade</artifactId>
  <version>1.78.1.0</version>
</dependency>
```

### Example

注意包名是 **com.github.leeyazhou.*.**

```java
import java.io.IOException;
import ja3.okhttp3.OkHttpClient;
import ja3.okhttp3.Request;
import ja3.okhttp3.Response;

public class TestOkhttp {

	public static void main(String[] args) throws IOException {
		String url = "https://www.baidu.com";
		OkHttpClient client = new OkHttpClient.Builder().build();
		Request.Builder request = new Request.Builder().url(url);
		try (Response response = client.newCall(request.build()).execute()) {
			System.out.println(response.body().string());
		}
	}
}
```


impersonator is a fork of [BouncyCastle-bctls](https://github.com/bcgit/bc-java/commit/74a62440c93342a6743bb33c36a5ee224fc6c885) and [okhttp](https://github.com/square/okhttp/tree/parent-4.12.0) that is designed to impersonate TLS fingerprints.

`impersonator` can
impersonate browsers' TLS/JA3 and HTTP/2 fingerprints. If you are blocked by some
website for no obvious reason, you can give `impersonator` a try.

## Features
- Supports TLS/JA3/JA4 fingerprints impersonation.
- Supports HTTP/2 fingerprints impersonation.
