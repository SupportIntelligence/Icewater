import "hash"

rule n3f0_1e9b19e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.1e9b19e9c8800b12"
     cluster="n3f0.1e9b19e9c8800b12"
     cluster_size="4912 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="mira otorunp advml"
     md5_hashes="['15dd99f1d93d48ad3317949e6674fbc6', '044830700cc89b27aa659a0f2b6fbc95', '1b53e67ef81bc5047ab5cfc3ac2711f3']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(72192,1024) == "070e485f2bbcc12c33c2e35c585c43b0"
}

