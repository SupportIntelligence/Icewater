
rule n3e9_11b8bcc18c001932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.11b8bcc18c001932"
     cluster="n3e9.11b8bcc18c001932"
     cluster_size="61"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbkrypt diple"
     md5_hashes="['01df1f66bfec32b44741dd36131aa527','0a5feae128658fbb5e54a07df100de4d','816f1e7532612ae35b33d68d93efbdb5']"

   strings:
      $hex_string = { dad6cacbbfb692958c17193cb9d5daf6f6f3d8c84b25000000252a32323f6dcaf2f2f6f9d74931303f49b5bcd7f0f2f2d8d5c1c0beb87a9491791a1f61d4f6da }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
