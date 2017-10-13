import "hash"

rule n3ed_39957a4fc2220b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.39957a4fc2220b32"
     cluster="n3ed.39957a4fc2220b32"
     cluster_size="21 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['c70a22d3285729f0e2eee2e3b9835f02', 'c36396341e0a5d8a524fee5b0e9913c0', 'c1b4d06ed7bc5dbe662aad698159429b']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(362496,1024) == "2c262d66b505baf68ab3851e94a5ba11"
}

