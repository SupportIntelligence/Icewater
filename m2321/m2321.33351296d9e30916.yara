
rule m2321_33351296d9e30916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.33351296d9e30916"
     cluster="m2321.33351296d9e30916"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zbot lethic gepys"
     md5_hashes="['1f29bdbef37a574a5aa3daf8f6df3bec','222b6829ddec8e1349af04057a883352','e5cc4306f9edd03d0840c69774bc049c']"

   strings:
      $hex_string = { 350c6059a599b21403e2bbde0f96f471a93de53fbc8c53a2212b78e1c156486417722511cc06376d19b5bd2aa3137f291eaa4031fb8e93addcb19a33e93ceb36 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
