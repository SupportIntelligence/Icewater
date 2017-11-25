
rule k3f4_275079d1c8000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.275079d1c8000330"
     cluster="k3f4.275079d1c8000330"
     cluster_size="463"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bladabindi backdoor cbbe"
     md5_hashes="['000df725e1d6461709fb0959f0776e6b','00c4f193ae2a20f56ad096c749a3dd48','0c7a5d6449c441eadd1c39c72ac440b5']"

   strings:
      $hex_string = { 72794b65795065726d697373696f6e436865636b0047657456616c75654e616d6573006765745f4c656e67746800436f6e7665727400546f4261736536345374 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
