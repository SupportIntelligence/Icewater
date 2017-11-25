
rule j2321_131257d2c92a7b36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.131257d2c92a7b36"
     cluster="j2321.131257d2c92a7b36"
     cluster_size="3"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre bublik generickd"
     md5_hashes="['61cae9d8f337cef85ca5ca46d690de4a','69ace514d0fde098f8573e848660c4e8','e6a76657e10cbd2107a8b4ca41cd3706']"

   strings:
      $hex_string = { 388a9134123158efb6f39da8fd18e547283f48f93ecab720ef0cde66197b1165e2c81781df72edfa1a6b510f683c4763bb149ccd23bdbc456d057c75dc5c5bd5 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
