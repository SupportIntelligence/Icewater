
rule k3f7_3312da9adebb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.3312da9adebb0912"
     cluster="k3f7.3312da9adebb0912"
     cluster_size="19"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html script"
     md5_hashes="['07dbd4cc5664dd2449ecd78df71faa5a','184faf0ab96b14328ff42eadd449d524','cf0aac46ac806143cbc603da68c0716c']"

   strings:
      $hex_string = { 3a2022392e302e30220a097d3b0a09536861646f77626f782e696e697428736861646f77626f785f636f6e66293b0a2f2a205d5d3e202a2f0a3c2f7363726970 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
