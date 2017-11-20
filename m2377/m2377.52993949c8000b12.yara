
rule m2377_52993949c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.52993949c8000b12"
     cluster="m2377.52993949c8000b12"
     cluster_size="21"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0110f611f4dcfa42c660b60c4736fd21','01efa1422c0e09cc6ea741bc0a9cbd55','d65d2886264a46705ad4a9cdc98e4b70']"

   strings:
      $hex_string = { 8fa400b57eb7ecdd3b762e7a5726cd958524cc98aabd6a38403d2cf8e4613966542bd3193f25aff5b84bd014974f289b2f777015a2516d827ce162f48cfd874c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
