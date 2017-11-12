
rule n3e9_131cbec9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.131cbec9c4000b12"
     cluster="n3e9.131cbec9c4000b12"
     cluster_size="314"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre otwycal wapomi"
     md5_hashes="['0861821f6f3c88fd755965f25846cd0d','0b38357ec0af3172ce560941533158a5','36b8d74a392ea0532e3f8735ef6f8078']"

   strings:
      $hex_string = { f7337fd597ea9b1e11fd487e21dcf33e4499a5627a3afec94d2a7b0cce976e8b8d7301ae3c14b4bb144b5876191af4a5f49e68c4eb5f8408e72dd9a31fb9a92b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
