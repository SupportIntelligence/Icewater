
rule m2321_1a58c868d912b912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.1a58c868d912b912"
     cluster="m2321.1a58c868d912b912"
     cluster_size="57"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="carberp shiz kazy"
     md5_hashes="['04d059131dcbdbdc4e2f8db26b26a55c','055fe1a215fc7d4e610c953506d84edf','40c8b5c7c8ef98539d975c44c8d95b68']"

   strings:
      $hex_string = { d3df3eb5c7602a754acfada6075fedd6252c627391b0be633b59807bea45e122bf3cf743f31a1ba18587e34d06f6a893578f4736d016b769e47233c5412b5608 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
