
rule k3ef_239c6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ef.239c6a48c0000b12"
     cluster="k3ef.239c6a48c0000b12"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kranet malicious corrupt"
     md5_hashes="['25bf30f3164939425d633b5af31d5b82','37d1c9a4e00e14affd95adf77f272895','fa5a97dcaede02fd5625e3ef05960534']"

   strings:
      $hex_string = { 3a2053797374656d2e5265666c656374696f6e2e417373656d626c795469746c652822446f744e65745a697020534658204172636869766522295d0a00005b61 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
