
rule m3e9_53a9213c80801132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.53a9213c80801132"
     cluster="m3e9.53a9213c80801132"
     cluster_size="3364"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob shodi"
     md5_hashes="['000eb97e5734d56b2c6ed30bb1476fca','0012762d59278a36c5c30fef8008ddcd','039057307c6958d8fbac5124390384ee']"

   strings:
      $hex_string = { 010203000411050612213113224151617114324281072352627291a1b133538292c1e1f015244363737493a2b2b3d1163435445483a3c2d3f10894d217255564 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
