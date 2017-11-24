
rule m3f9_325546a4ed011b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f9.325546a4ed011b12"
     cluster="m3f9.325546a4ed011b12"
     cluster_size="60"
     filetype = "MS-DOS executable"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi mofksys abzf"
     md5_hashes="['188746ddf39e7630032565633193e265','6408f5418b5ee29c409c976f0792526f','acae59bca1b18ab10de1a25bff4b4ce8']"

   strings:
      $hex_string = { 6a108b490c03c8518b1752e868f1feffffd68d459450ffd38b4db885c974266683390175200fbf5dc02b59143b59107209ff15d41040008b4db8c1e304899d38 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
