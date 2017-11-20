
rule k403_139254f9c9000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k403.139254f9c9000b16"
     cluster="k403.139254f9c9000b16"
     cluster_size="3877"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hackkms hacktool risktool"
     md5_hashes="['0023bd24cb92f2d915fa439ef6d86483','004fb97d32df5156dfeacc0cfad89167','0167e811200077d9be73e198652a5f43']"

   strings:
      $hex_string = { 57538d45fc50e8d57e000085c07c2d8b45fc33d28bcbf7f13bc676208bd78945f88b4d0c8b7d088d720a33c0f3a675058b028945f403d3ff4df875e5685f4449 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
