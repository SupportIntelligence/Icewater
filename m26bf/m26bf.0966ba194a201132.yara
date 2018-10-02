
rule m26bf_0966ba194a201132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bf.0966ba194a201132"
     cluster="m26bf.0966ba194a201132"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="msilperseus genericrxfs hacktool"
     md5_hashes="['2f9c379144d0a33d110431922252ef4029d312c2','acfbf325a01dd639a2bd092c71db73ba553acfc8','3d17cf4cc783039d59a00dd5a37efdb31c40e409']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bf.0966ba194a201132"

   strings:
      $hex_string = { 253ce95aa99999d9ae5dbb60d3dcc3b5e88777efdefdc17ea84135ffea891a7b817d010ba3b14690f3a29b8b626ec724be9f987c3739fadd68046a4ce7643eec }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
