
rule m2321_39521290d6c30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.39521290d6c30912"
     cluster="m2321.39521290d6c30912"
     cluster_size="10"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small generickd upatre"
     md5_hashes="['0f8e7a42a96d90aa929204ddb46f5560','2406b68544adf2ab60165a7a57906c74','cfd3efceef6c8779bb5133392ee023bf']"

   strings:
      $hex_string = { a5c8857be7b803ea7d101b0d715231a35d554cac07d8462cefbc06bb04fc8ade2ad2d73ed149b735ed901c10f3e56ba069486de69cb41930bab609aeb1a43a7c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
