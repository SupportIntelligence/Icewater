
rule n26ef_119d8cc8c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26ef.119d8cc8c4000b12"
     cluster="n26ef.119d8cc8c4000b12"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="olext cosmu malicious"
     md5_hashes="['9e3d134e847bd9cf01cb1df1ba12e9f135c5fcf9','6eb0519d39434a4577e7f0bb84fb6572fd196df4','c1d3cc4d0f18c30d401b28c6b9de38a6a08b6389']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26ef.119d8cc8c4000b12"

   strings:
      $hex_string = { 62ceb46b2a1237a3b71ee1dad467b5ccd07d996fa7824c8d79ea87559d27adddd202e5718638438f2afc08229628c45d64d920cd03344e9c119848a5b084f10f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
