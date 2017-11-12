
rule k3e9_2bc4eb50c926f1a3
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2bc4eb50c926f1a3"
     cluster="k3e9.2bc4eb50c926f1a3"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ibryte installer optimum"
     md5_hashes="['28e53842e6993637b76fd4a4d96c26bb','2ff98c76f3b47d16c621f6f4d344f634','e5a477b7cf1929951bc584147387a424']"

   strings:
      $hex_string = { 2f63726c2e636f6d6f646f63612e636f6d2f434f4d4f444f436f64655369676e696e674341322e63726c307206082b0601050507010104663064303c06082b06 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
