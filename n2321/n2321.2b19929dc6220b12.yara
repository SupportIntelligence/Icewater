
rule n2321_2b19929dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.2b19929dc6220b12"
     cluster="n2321.2b19929dc6220b12"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod viking"
     md5_hashes="['050745cb5a9eab771a76d59ae93653a6','0db8d06a77b30fb313310ddce3289291','f7d1fe60056163a61b319dd3399fef05']"

   strings:
      $hex_string = { 8e1c4287842971304175ceb974f4df5cd798e4bc3be71da3226db726c863c6c00c60271278fe3e6c1f2ba88cba61d923e61096ae372c1e20060a3a4cbd2d435a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
