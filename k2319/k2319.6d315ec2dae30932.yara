
rule k2319_6d315ec2dae30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.6d315ec2dae30932"
     cluster="k2319.6d315ec2dae30932"
     cluster_size="27"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cryxos html fakealert"
     md5_hashes="['2da118ed015c8df8e914bb1940ddeab91ae85449','edc988afbf2e63670fcf1afb1e0dc4d3d5089726','99c2f70b205fe17e51f4bdfcad630484a958abb0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.6d315ec2dae30932"

   strings:
      $hex_string = { 49752b377679496761575139496c63315454424e63454e6c61476c49656e4a6c5533704f56474e3661324d355a43492f5069413865447034625842745a585268 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
