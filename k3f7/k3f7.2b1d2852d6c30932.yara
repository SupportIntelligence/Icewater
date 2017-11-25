
rule k3f7_2b1d2852d6c30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.2b1d2852d6c30932"
     cluster="k3f7.2b1d2852d6c30932"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html script"
     md5_hashes="['0a90cd76b43542b72f05dc02866c3bce','1e95565cef68b6cc9812fc40fdb3270a','69c4c4e4c05ddf6f3a956969ce03d506']"

   strings:
      $hex_string = { 3037363138383831345c783236636f6c6f72735c78336443677430636d467563334268636d56756442494c64484a68626e4e7759584a6c626e516142794d7a4d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
