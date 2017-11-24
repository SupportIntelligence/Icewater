
rule m2321_2b969518dee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2b969518dee30932"
     cluster="m2321.2b969518dee30932"
     cluster_size="8"
     filetype = "MS-DOS executable (gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="enistery dynamer pemalform"
     md5_hashes="['16fb97d2cd27ee5de7c0b5071143bd77','3c62ec35c5529648f0fc64bf0dc711d8','f7a22c9ddb0b4f88ebbc13c42fb76cb1']"

   strings:
      $hex_string = { 77c64d7086a29915abf44d6acef17b28cf36e1b96e4564630b41ef6919c71462af24b44608ee52799c84679e958991884abde2566c858b184c34d3b8c29aecfe }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
