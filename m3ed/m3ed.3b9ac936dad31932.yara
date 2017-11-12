
rule m3ed_3b9ac936dad31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.3b9ac936dad31932"
     cluster="m3ed.3b9ac936dad31932"
     cluster_size="42"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul malicious"
     md5_hashes="['0252bebbf5ad6b80a621ef4f9f5c7949','0579267962941b3f7ad98830595cce13','a47e521c55b8d00e904dec531b0712df']"

   strings:
      $hex_string = { 44494e47585850414444494e4750414444494e47585850414444494e4750414444494e47585850414444494e4750414444494e47585850414444494e47504144 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
