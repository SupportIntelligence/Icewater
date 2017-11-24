
rule o3e9_2b627c66919b1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2b627c66919b1912"
     cluster="o3e9.2b627c66919b1912"
     cluster_size="1488"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small keylogger riskware"
     md5_hashes="['001317652cf78e080729ba525aa5ee32','0036eb2219807d093140443b427c5291','03421ebd67c9775314b8cb40366384b8']"

   strings:
      $hex_string = { a0bd5c1ac2d28f1d7ebc399f58360a664fc46155fdcfa89101b725d4172980d63e50dd7f485d43d165e05771311ca737d0003cbbe5abfac5e9f022626d9dda24 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
