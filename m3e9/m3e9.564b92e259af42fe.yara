
rule m3e9_564b92e259af42fe
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.564b92e259af42fe"
     cluster="m3e9.564b92e259af42fe"
     cluster_size="449"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chir runouce virut"
     md5_hashes="['0013323f41f8a1d7399a95f6be9a52f2','001c4d57cee2b2309f2559ac3c8ec3eb','0679b22dd3e0ae241ab1e1247eba6aa2']"

   strings:
      $hex_string = { 004142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738392b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
