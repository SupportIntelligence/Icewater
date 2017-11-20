
rule m3e9_316338779f3b1112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.316338779f3b1112"
     cluster="m3e9.316338779f3b1112"
     cluster_size="167"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod malicious"
     md5_hashes="['00db8a1f2425e60b8ce34d4450fd6601','0307062fda837d562dd656b44019e8c5','6f5212c4ebe4c24ab5d0568379e4ca41']"

   strings:
      $hex_string = { 3c24f1cb70f6799caa4ae59fe87d1961cc14fad3d636fcd1a7e22311228c5a0449ba9868ce690637419175e94f91bbfe86a83ef808ebc36c3f5f3932a6b7c7ed }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
