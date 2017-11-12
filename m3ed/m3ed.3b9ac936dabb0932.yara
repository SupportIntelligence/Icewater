
rule m3ed_3b9ac936dabb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.3b9ac936dabb0932"
     cluster="m3ed.3b9ac936dabb0932"
     cluster_size="10"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul malicious"
     md5_hashes="['a09574ccae6edce8f9c1af3f5df0fcbb','a1f9f5780dbc52f8ae528aef64348399','dd745836360e1e0e5cfc6acc2828f57e']"

   strings:
      $hex_string = { 44494e47585850414444494e4750414444494e47585850414444494e4750414444494e47585850414444494e4750414444494e47585850414444494e47504144 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
