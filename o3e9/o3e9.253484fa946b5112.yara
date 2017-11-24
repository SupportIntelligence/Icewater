
rule o3e9_253484fa946b5112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.253484fa946b5112"
     cluster="o3e9.253484fa946b5112"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmu mikey malicious"
     md5_hashes="['06e5cd20d733696e2d400220aab1b21c','b827286113d68eb2351b7553caaef16b','eab02e0b1960b6b18f2626eae2c38342']"

   strings:
      $hex_string = { 7fd788098710db768fad6786c5683becbb997750322736016f053d07f29d1ec83eb0b530792572f9cd297ecfe7f1822f7a3146c99b8c7de9542106a569ac49cb }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
