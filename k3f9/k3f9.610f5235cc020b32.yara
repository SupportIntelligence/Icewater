
rule k3f9_610f5235cc020b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f9.610f5235cc020b32"
     cluster="k3f9.610f5235cc020b32"
     cluster_size="163"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="sirefef malicious pemalform"
     md5_hashes="['02b43ad2d54af57124e96f3e7c317f4e','080a78071b2ec09c3ed2ebff859394b4','34794d41eb56badfb378b1864b3470de']"

   strings:
      $hex_string = { 30fe3008313e317b31d131e4318f3278331b349e34b034c334c834d234e034ff340a351635233539354335cf36e336f336123724374a3753376c37853728382e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
