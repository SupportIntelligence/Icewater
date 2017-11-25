
rule k3ec_331c1499c6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.331c1499c6220b32"
     cluster="k3ec.331c1499c6220b32"
     cluster_size="6336"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hackkms riskware autokms"
     md5_hashes="['00022a0b27fd749b27ca27a8215a343f','0012eecff291fc1d311a4f5d8e49ebeb','0101d6cef38ceb3f78a458525c7b1793']"

   strings:
      $hex_string = { ffcfc715a9d1f3bc975926378c11606498c23d125cbb20781f01a399fd5b8f9019e6f938e2b162aac88b523186eca89129ba74957d65dfd7e14d1bb32efeab2b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
