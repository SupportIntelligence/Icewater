
rule m3e9_4c1e339bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4c1e339bc6220b12"
     cluster="m3e9.4c1e339bc6220b12"
     cluster_size="11"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['0bb6180089649cafe01baf1f663d23d3','2fb176d4926834c49ef4e57af384ec1e','e134747e5a285aeaf9d003328613a9b0']"

   strings:
      $hex_string = { dfaa0b745625bad07ab029f7a99eb7e9e96fccbed448ad6f3bff5a7d55cdf88b989f576ec0e2edafc9f2a2902f7ef5c971755926982cb3e9c262c969af4afe41 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
