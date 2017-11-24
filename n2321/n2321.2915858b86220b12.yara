
rule n2321_2915858b86220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.2915858b86220b12"
     cluster="n2321.2915858b86220b12"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['8d8fbe203039e3abafb5dc1b62d58e29','d560c9438309541c19e72a31de1f0c6b','f38dfba3aa836aaef0b1d8b6968e13da']"

   strings:
      $hex_string = { 79a2e206e5592edc3d574f92e12543772f60b4a18bd72b682a2624d9e34028a57d0195b827bf457b6f823a4af854bca8f2f465387f8d56ad533e110eaf19d69b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
