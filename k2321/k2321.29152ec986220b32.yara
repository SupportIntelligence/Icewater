
rule k2321_29152ec986220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.29152ec986220b32"
     cluster="k2321.29152ec986220b32"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok email pazetus"
     md5_hashes="['0a84f643f008abfc2608aa668c6ec549','385abfa54a4ff395c4315d4b2b90c311','f344731fe404a69694c164a96927e1b0']"

   strings:
      $hex_string = { 64bfdc189ee8164d853ccad9c27cbd8ab2f31ad628ed33b666c59d4d0b5d5b7a1091358cf752b13e88cc0c82983662c3530438b0342957307bbcf011588f7efd }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
