
rule n3e9_12969cb3c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.12969cb3c2000b32"
     cluster="n3e9.12969cb3c2000b32"
     cluster_size="45"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zegost backdoor farfli"
     md5_hashes="['0e99290836150b49df4f965820e34aeb','0fb5109887a9de3f998fa4dcaa2a1fbf','b19b99b351a1045c5370546e5435d657']"

   strings:
      $hex_string = { 50ffd38b54245883c4408d450156575052ffd38b44242856578d48ff8d45015051894c2448ffd35657558b6c245455ffd38b4c244056575155ffd383c4405f5e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
