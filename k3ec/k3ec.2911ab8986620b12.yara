
rule k3ec_2911ab8986620b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.2911ab8986620b12"
     cluster="k3ec.2911ab8986620b12"
     cluster_size="7"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok email pazetus"
     md5_hashes="['3742c343f1796279047229e219f5e902','45630a186222e71e8ab7ceda14ee2b0f','f1e28d027546a04c7ee8891726274bda']"

   strings:
      $hex_string = { 68a5b926f3e5c6f044b7482ae451ce16f6eb55b4add7b07a699f91152bee6c5ae8dad28388ac618297b2d541546610c4a411179ec2cf81a349ba80d9e3858ec0 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
