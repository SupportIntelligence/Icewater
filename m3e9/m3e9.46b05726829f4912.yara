
rule m3e9_46b05726829f4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.46b05726829f4912"
     cluster="m3e9.46b05726829f4912"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus jorik malicious"
     md5_hashes="['028314a299cedfe1fbfc49960cd951af','a5487d86dae831c1ee1636d3c0b149cf','ebf42079ec06ce191404078cc3cbd385']"

   strings:
      $hex_string = { 66676e5f6e59556f987a726f6d7990a2dcf9fffdfff7f7b7000000f8ffff0312282c20101111101a585765736c30667a635f5c75b3a79cc0cecdaea9aae6f2fa }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
