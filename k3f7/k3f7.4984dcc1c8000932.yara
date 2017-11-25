
rule k3f7_4984dcc1c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.4984dcc1c8000932"
     cluster="k3f7.4984dcc1c8000932"
     cluster_size="49"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector script html"
     md5_hashes="['00778ec14ef99e89ed530afe72568737','0a490d214002fc52b556a6f0e6e875b9','5c11526a5c7196b6fb52e95371fb0a7a']"

   strings:
      $hex_string = { 6669656c642e64656661756c7456616c75653b207d207d0d0a3c2f7363726970743e0d0a3c21444f43545950452068746d6c205055424c494320222d2f2f5733 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
