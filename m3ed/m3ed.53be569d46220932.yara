
rule m3ed_53be569d46220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.53be569d46220932"
     cluster="m3ed.53be569d46220932"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul autorun"
     md5_hashes="['3d0f62dd910fb54c6528be3c9160e2a2','ac17b3dcdc06da0b703608d478369081','ad18c0639003068ac4d123fe898e663d']"

   strings:
      $hex_string = { 3bc77513ff150cc0001085c0740950e835aaffff59ebcf8bc6c1f8058b0485601d011083e61fc1e6068d4430048020fd8b45f88b55fc5f5ec9c36a1468e0d700 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
