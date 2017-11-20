
rule m3e9_2705a969c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2705a969c8800932"
     cluster="m3e9.2705a969c8800932"
     cluster_size="200"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus sirefef vbinject"
     md5_hashes="['011c3be116f8e292ef90fa3a6377bd07','04c52c6527ae5ec2812b3b72b6b07fe1','2c0ae37e500e1e185182bf9f5840c477']"

   strings:
      $hex_string = { f7f6f1dbd6c5bfbcb185959c900721b5f3f3f3dbdcdbc63e250000002430333252bdf3f1f6f7f7ef400b2e34343457b4d5f6efd9d9bfbfb97aa993969709147c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
