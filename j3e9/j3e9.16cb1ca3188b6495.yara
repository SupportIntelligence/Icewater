
rule j3e9_16cb1ca3188b6495
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.16cb1ca3188b6495"
     cluster="j3e9.16cb1ca3188b6495"
     cluster_size="15"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="madangel small madang"
     md5_hashes="['1c289da1e9873f617b5117ba36ba2a74','56c8f7bc3f2fd457a694e03b34ce9c43','fce3e537be1abee5df851f2e88c8f626']"

   strings:
      $hex_string = { 66813e4d5a78037901eb75ee0fb77e3c03fe8b6f7803ee8b5d2003de33c08bd683c304408b3b03fae80f00000047657450726f6341646472657373005e33c9b1 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
