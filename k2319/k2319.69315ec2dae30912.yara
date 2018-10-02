
rule k2319_69315ec2dae30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.69315ec2dae30912"
     cluster="k2319.69315ec2dae30912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html cryxos fakealert"
     md5_hashes="['2ec5975724ff263acafbbff8ac094e366f693125','938167f9b4ee831f7eefdb84ba03ecdcd7b195e4','5e22445586375f282073134acb0d3883d08056c0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.69315ec2dae30912"

   strings:
      $hex_string = { 49752b377679496761575139496c63315454424e63454e6c61476c49656e4a6c5533704f56474e3661324d355a43492f5069413865447034625842745a585268 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
