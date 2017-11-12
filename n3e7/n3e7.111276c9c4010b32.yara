
rule n3e7_111276c9c4010b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.111276c9c4010b32"
     cluster="n3e7.111276c9c4010b32"
     cluster_size="13"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="downloadguide malicious applicunsaf"
     md5_hashes="['0ae82fce24369617b29aad67f92b8829','2177ccc5d4263d4ab89a47c54f751761','e98420d4462b848d11e3d92f645235bb']"

   strings:
      $hex_string = { 3bc77513ff15ac41460085c0740950e8dc8affff59ebcf8bc6c1f8058b0485e0a7480083e61fc1e6068d4430048020fd8b45f88b55fc5f5ec9c36a1468a01348 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
