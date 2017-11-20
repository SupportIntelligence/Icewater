
rule m3ed_53be109d46220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.53be109d46220932"
     cluster="m3ed.53be109d46220932"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul autorun"
     md5_hashes="['95bec4afc2b56d21861a5ceadf5f592c','97a3ef2b3b929c55fce19bfb3d31c821','db1f41a436de738b8dd0f98044f45cce']"

   strings:
      $hex_string = { 3bc77513ff150cc0001085c0740950e835aaffff59ebcf8bc6c1f8058b0485601d011083e61fc1e6068d4430048020fd8b45f88b55fc5f5ec9c36a1468e0d700 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
