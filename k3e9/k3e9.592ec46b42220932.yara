
rule k3e9_592ec46b42220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.592ec46b42220932"
     cluster="k3e9.592ec46b42220932"
     cluster_size="31"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbna chinky vobfus"
     md5_hashes="['253b505feac12b470e2076ff2d5b08ae','5332444cedf9c36f259e99ad453d7980','c5fae856c186a6cfcc3b1ae4ac6a0fb6']"

   strings:
      $hex_string = { 002fa4fc365a0088fd78fd68fd58fd48fd38fd28fd18fd08fdf8fce8fcd8fcc8fcb8fca8fc68ff58ff48ff38ff28ff18ff08fff8fee8fed8fec8feb8fea8fe98 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
