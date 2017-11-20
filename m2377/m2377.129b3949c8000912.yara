
rule m2377_129b3949c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.129b3949c8000912"
     cluster="m2377.129b3949c8000912"
     cluster_size="8"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['119345cd51c694f4ad331b3e359af3bc','1542f34f4687f32433bf1ee16dc840a5','f5928dfbe9b945cbe8648278c9b2ad1a']"

   strings:
      $hex_string = { 83ce15ab6e885da4bd2ef034b0148c59c0162a13494543d4190d5e9618c1b13dc5dfa6f60424deeccab995e620586bac93a3f144099846b55f1dcb54bb7da723 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
