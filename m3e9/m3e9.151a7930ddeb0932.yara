
rule m3e9_151a7930ddeb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.151a7930ddeb0932"
     cluster="m3e9.151a7930ddeb0932"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['a3d899e575823d63115b63e4d8c7082e','a96f93a0e568e1e85dbeba44357cffd5','cd466bb4033c5ef5091e32b92eaa6f90']"

   strings:
      $hex_string = { bd19570640346313790cfd3a804def90c9af1e486c37d96d5ef607835acb707c28f261aacdc06aa05a81c2e72f2564771e60825999e2f1e01ec40635f17f3189 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
