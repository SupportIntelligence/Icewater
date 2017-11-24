
rule m3e9_29152b932ee10b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.29152b932ee10b12"
     cluster="m3e9.29152b932ee10b12"
     cluster_size="18"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi vbobfus"
     md5_hashes="['a4bc32c1ff321db528ecaf2dd4640b63','a4cf9044c0b212d0bf0a50da9c3b7384','e300eddcb862b271ab574a9811e8b176']"

   strings:
      $hex_string = { 2323222020161515111707021848656565654b595c7d7d7d7c7a7a777776765d5d5d34031842512b2b4a255a5e93939292919190908f8f8f8e823b0444536e2e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
