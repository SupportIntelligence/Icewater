import "hash"

rule n3e9_1ba57ec1c4000916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1ba57ec1c4000916"
     cluster="n3e9.1ba57ec1c4000916"
     cluster_size="1247 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="pykspa vilsel pykse"
     md5_hashes="['4da8a5a98022b5bf99013440253cc035', '15f33376259f3f097ddc8d056ada599d', '11ed322f4f30cd3c04f8c4ae7371b543']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(184320,1024) == "4a7eda87e55f7b49d27eddf547ee733b"
}

